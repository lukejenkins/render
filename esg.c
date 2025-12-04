#include "esg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    TABLE_TYPE_UNKNOWN,
    TABLE_TYPE_SLT,
    TABLE_TYPE_SYSTEM_TIME,
    TABLE_TYPE_UCT,
    TABLE_TYPE_CDT,
    TABLE_TYPE_UDST,
    TABLE_TYPE_SIGNATURE,
    TABLE_TYPE_FDT,
    TABLE_TYPE_MPD,
    TABLE_TYPE_HELD,
    TABLE_TYPE_ESG_FRAGMENT,
    TABLE_TYPE_SGDD,
    TABLE_TYPE_USER_SERVICE_DESCRIPTION,
    TABLE_TYPE_SERVICE_SIGNALING,
    TABLE_TYPE_STSID,
    TABLE_TYPE_MP_TABLE_XML,
    TABLE_TYPE_MP_TABLE_BINARY,
    TABLE_TYPE_MP_TABLE_PATTERN_MATCHED,
    TABLE_TYPE_USBD,
    TABLE_TYPE_USD,
    TABLE_TYPE_DWD,
    TABLE_TYPE_LMT
} TableType;

typedef struct {
    char* content_id;
    void* parsed_data;
    TableType type;
    char destinationIp[40];
    char destinationPort[16];
} LlsTable;

// Forward declare external dependencies
extern int g_lls_table_count;
extern void* g_lls_tables; // You'll need to properly type this

/**
 * @brief Enhanced ESG parser that extracts services, programs, schedules, and media assets
 */
EsgFragmentData* parse_esg_service_fragment(xmlDocPtr doc) {
    EsgFragmentData* esg_data = calloc(1, sizeof(EsgFragmentData));
    if (!esg_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);

    if (xmlStrcmp(root->name, (const xmlChar *)"Service") == 0) {
        parse_esg_service(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Program") == 0) {
        parse_esg_program(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Schedule") == 0) {
        parse_esg_schedule(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"ServiceBundle") == 0) {
        parse_esg_service_bundle(root, esg_data);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Content") == 0) {
        parse_esg_content(root, esg_data);
    }
    
    return esg_data;
}

void parse_esg_service(xmlNodePtr service_node, EsgFragmentData* esg_data) {
    EsgServiceInfo* service = calloc(1, sizeof(EsgServiceInfo));
    if (!service) return;

    xmlChar* prop;
    
    // Basic service attributes
    prop = xmlGetProp(service_node, (const xmlChar *)"id");
    if(prop) { strncpy(service->id, (char*)prop, sizeof(service->id)-1); xmlFree(prop); }
    
    prop = xmlGetProp(service_node, (const xmlChar *)"serviceStatus");
    if(prop) { strncpy(service->serviceStatus, (char*)prop, sizeof(service->serviceStatus)-1); xmlFree(prop); }
    
    prop = xmlGetProp(service_node, (const xmlChar *)"globalServiceID");
    if(prop) { strncpy(service->serviceStatus, (char*)prop, sizeof(service->serviceStatus)-1); xmlFree(prop); }

    // Parse child elements
    xmlNodePtr child = service_node->children;
    EsgMediaAsset* icon_tail = NULL;
    EsgScheduleEvent* schedule_tail = NULL;
    
    while(child != NULL) {
        if(child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Name") == 0) {
                // FIXED: Try "text" attribute first (OMA ESG format)
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(service->name, (char*)prop, sizeof(service->name)-1);
                    xmlFree(prop);
                } else {
                    // Fallback to element content
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(service->name, (char*)content, sizeof(service->name)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Description") == 0) {
                // FIXED: Try "text" attribute first
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(service->description, (char*)prop, sizeof(service->description)-1);
                    xmlFree(prop);
                } else {
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(service->description, (char*)content, sizeof(service->description)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Genre") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(service->genre, (char*)content, sizeof(service->genre)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ServiceIcon") == 0 ||
                       xmlStrcmp(child->name, (const xmlChar *)"Icon") == 0) {
                EsgMediaAsset* icon = parse_esg_media_asset(child, "serviceIcon");
                if(icon) {
                    if(!service->icons) {
                        service->icons = icon;
                        icon_tail = icon;
                    } else {
                        icon_tail->next = icon;
                        icon_tail = icon;
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Schedule") == 0) {
                parse_esg_schedule_events(child, &service->schedule, &schedule_tail);
            } else if (xmlStrcmp(child->name, (const xmlChar *)"PrivateExt") == 0) {
                // Look for ATSC3ServiceExtension
                xmlNodePtr ext_child = child->children;
                while (ext_child) {
                    if (ext_child->type == XML_ELEMENT_NODE &&
                        xmlStrcmp(ext_child->name, (const xmlChar *)"ATSC3ServiceExtension") == 0) {
                        xmlNodePtr channel_child = ext_child->children;
                        while (channel_child) {
                            if (channel_child->type == XML_ELEMENT_NODE) {
                                if (xmlStrcmp(channel_child->name, (const xmlChar *)"MajorChannelNum") == 0) {
                                    xmlChar* content = xmlNodeGetContent(channel_child);
                                    if (content) {
                                        strncpy(service->majorChannel, (char*)content, sizeof(service->majorChannel)-1);
                                        xmlFree(content);
                                    }
                                } else if (xmlStrcmp(channel_child->name, (const xmlChar *)"MinorChannelNum") == 0) {
                                    xmlChar* content = xmlNodeGetContent(channel_child);
                                    if (content) {
                                        strncpy(service->minorChannel, (char*)content, sizeof(service->minorChannel)-1);
                                        xmlFree(content);
                                    }
                                }
                            }
                            channel_child = channel_child->next;
                        }
                    }
                    ext_child = ext_child->next;
                }
            }
        }
        child = child->next;
    }

    // Add to service list
    service->next = esg_data->services;
    esg_data->services = service;
}

void parse_esg_program(xmlNodePtr program_node, EsgFragmentData* esg_data) {
    EsgProgramInfo* program = calloc(1, sizeof(EsgProgramInfo));
    if (!program) return;

    xmlChar* prop;
    
    prop = xmlGetProp(program_node, (const xmlChar *)"id");
    if(prop) { strncpy(program->id, (char*)prop, sizeof(program->id)-1); xmlFree(prop); }

    // Parse program details
    xmlNodePtr child = program_node->children;
    EsgMediaAsset* icon_tail = NULL;
    EsgContentRating* rating_tail = NULL;
    
    while(child != NULL) {
        if(child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Title") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(program->title, (char*)content, sizeof(program->title)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Description") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(program->description, (char*)content, sizeof(program->description)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Genre") == 0) {
                xmlChar* content = xmlNodeGetContent(child);
                if(content) {
                    strncpy(program->genre, (char*)content, sizeof(program->genre)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ProgramIcon") == 0 ||
                       xmlStrcmp(child->name, (const xmlChar *)"Icon") == 0) {
                EsgMediaAsset* icon = parse_esg_media_asset(child, "programIcon");
                if(icon) {
                    if(!program->icons) {
                        program->icons = icon;
                        icon_tail = icon;
                    } else {
                        icon_tail->next = icon;
                        icon_tail = icon;
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"ContentRating") == 0) {
                EsgContentRating* rating = parse_esg_content_rating(child);
                if(rating) {
                    if(!program->ratings) {
                        program->ratings = rating;
                        rating_tail = rating;
                    } else {
                        rating_tail->next = rating;
                        rating_tail = rating;
                    }
                }
            }
        }
        child = child->next;
    }

    // Add to program list
    program->next = esg_data->programs;
    esg_data->programs = program;
}

EsgMediaAsset* parse_esg_media_asset(xmlNodePtr asset_node, const char* usage_type) {
    EsgMediaAsset* asset = calloc(1, sizeof(EsgMediaAsset));
    if (!asset) return NULL;

    strcpy(asset->usage, usage_type);

    xmlChar* prop;
    prop = xmlGetProp(asset_node, (const xmlChar *)"uri");
    if(!prop) prop = xmlGetProp(asset_node, (const xmlChar *)"href");
    if(!prop) prop = xmlGetProp(asset_node, (const xmlChar *)"src");
    if(prop) { strncpy(asset->uri, (char*)prop, sizeof(asset->uri)-1); xmlFree(prop); }

    prop = xmlGetProp(asset_node, (const xmlChar *)"contentType");
    if(!prop) prop = xmlGetProp(asset_node, (const xmlChar *)"mimeType");
    if(prop) { strncpy(asset->contentType, (char*)prop, sizeof(asset->contentType)-1); xmlFree(prop); }

    prop = xmlGetProp(asset_node, (const xmlChar *)"width");
    if(prop) { strncpy(asset->width, (char*)prop, sizeof(asset->width)-1); xmlFree(prop); }

    prop = xmlGetProp(asset_node, (const xmlChar *)"height");
    if(prop) { strncpy(asset->height, (char*)prop, sizeof(asset->height)-1); xmlFree(prop); }

    return asset;
}

void parse_esg_content(xmlNodePtr content_node, EsgFragmentData* esg_data) {
    xmlChar* prop;
    
    // Create a program entry from the Content element
    EsgProgramInfo* program = calloc(1, sizeof(EsgProgramInfo));
    if (!program) return;
    
    // Get content ID if available
    prop = xmlGetProp(content_node, (const xmlChar *)"id");
    if(prop) { 
        strncpy(program->id, (char*)prop, sizeof(program->id)-1); 
        xmlFree(prop); 
    }
    
    xmlNodePtr child = content_node->children;
    while (child) {
        if (child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Name") == 0) {
                // Try "text" attribute first (OMA ESG format)
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(program->title, (char*)prop, sizeof(program->title)-1);
                    xmlFree(prop);
                } else {
                    // Fallback to element content
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(program->title, (char*)content, sizeof(program->title)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Description") == 0) {
                // Try "text" attribute first (OMA ESG format)
                prop = xmlGetProp(child, (const xmlChar *)"text");
                if(prop) {
                    strncpy(program->description, (char*)prop, sizeof(program->description)-1);
                    xmlFree(prop);
                } else {
                    // Fallback to element content
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(program->description, (char*)content, sizeof(program->description)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Genre") == 0) {
                // Try href attribute or element content
                prop = xmlGetProp(child, (const xmlChar *)"href");
                if(prop) {
                    strncpy(program->genre, (char*)prop, sizeof(program->genre)-1);
                    xmlFree(prop);
                } else {
                    xmlChar* content = xmlNodeGetContent(child);
                    if(content) {
                        strncpy(program->genre, (char*)content, sizeof(program->genre)-1);
                        xmlFree(content);
                    }
                }
            } else if (xmlStrcmp(child->name, (const xmlChar *)"MediaAsset") == 0 ||
                       xmlStrcmp(child->name, (const xmlChar *)"Icon") == 0) {
                EsgMediaAsset* icon = parse_esg_media_asset(child, "programIcon");
                if(icon) {
                    icon->next = program->icons;
                    program->icons = icon;
                }
            }
        }
        child = child->next;
    }
    
    // Add to program list
    program->next = esg_data->programs;
    esg_data->programs = program;
}

EsgContentRating* parse_esg_content_rating(xmlNodePtr rating_node) {
    EsgContentRating* rating = calloc(1, sizeof(EsgContentRating));
    if (!rating) return NULL;

    xmlChar* prop;
    prop = xmlGetProp(rating_node, (const xmlChar *)"scheme");
    if(prop) { strncpy(rating->scheme, (char*)prop, sizeof(rating->scheme)-1); xmlFree(prop); }

    prop = xmlGetProp(rating_node, (const xmlChar *)"value");
    if(!prop) {
        xmlChar* content = xmlNodeGetContent(rating_node);
        if(content) {
            strncpy(rating->value, (char*)content, sizeof(rating->value)-1);
            xmlFree(content);
        }
    } else {
        strncpy(rating->value, (char*)prop, sizeof(rating->value)-1);
        xmlFree(prop);
    }

    return rating;
}

void parse_esg_schedule_events(xmlNodePtr schedule_node, EsgScheduleEvent** head, EsgScheduleEvent** tail) {
    xmlNodePtr event_node = schedule_node->children;
    
    while(event_node != NULL) {
        if(event_node->type == XML_ELEMENT_NODE && 
           (xmlStrcmp(event_node->name, (const xmlChar *)"ScheduleEvent") == 0 ||
            xmlStrcmp(event_node->name, (const xmlChar *)"Event") == 0)) {
            
            EsgScheduleEvent* event = calloc(1, sizeof(EsgScheduleEvent));
            if(event) {
                xmlChar* prop;
                prop = xmlGetProp(event_node, (const xmlChar *)"startTime");
                if(prop) { strncpy(event->startTime, (char*)prop, sizeof(event->startTime)-1); xmlFree(prop); }
                
                prop = xmlGetProp(event_node, (const xmlChar *)"duration");
                if(prop) { strncpy(event->duration, (char*)prop, sizeof(event->duration)-1); xmlFree(prop); }
                
                prop = xmlGetProp(event_node, (const xmlChar *)"programId");
                if(prop) { strncpy(event->programId, (char*)prop, sizeof(event->programId)-1); xmlFree(prop); }

                if(!*head) {
                    *head = event;
                    *tail = event;
                } else {
                    (*tail)->next = event;
                    *tail = event;
                }
            }
        }
        event_node = event_node->next;
    }
}

void parse_esg_service_bundle(xmlNodePtr bundle_node, EsgFragmentData* esg_data) {
    xmlNodePtr child = bundle_node->children;
    
    while(child != NULL) {
        if(child->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(child->name, (const xmlChar *)"Service") == 0) {
                parse_esg_service(child, esg_data);
            } else if (xmlStrcmp(child->name, (const xmlChar *)"Program") == 0) {
                parse_esg_program(child, esg_data);
            }
        }
        child = child->next;
    }
}

void parse_esg_schedule(xmlNodePtr schedule_node, EsgFragmentData* esg_data) {
    // This would parse standalone schedule fragments
    // Implementation depends on specific ESG schedule format
}

SgddData* parse_sgdd(xmlDocPtr doc) {
    SgddData* sgdd = calloc(1, sizeof(SgddData));
    if (!sgdd) return NULL;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    
    xmlChar* prop = xmlGetProp(root, (const xmlChar *)"id");
    if (prop) {
        strncpy(sgdd->id, (char*)prop, sizeof(sgdd->id)-1);
        xmlFree(prop);
    }
    
    prop = xmlGetProp(root, (const xmlChar *)"version");
    if (prop) {
        strncpy(sgdd->version, (char*)prop, sizeof(sgdd->version)-1);
        xmlFree(prop);
    }
    
    // Parse DescriptorEntry elements
    xmlNodePtr entry_node = root->children;
    SgddEntry* entry_tail = NULL;
    
    while (entry_node) {
        if (entry_node->type == XML_ELEMENT_NODE &&
            xmlStrcmp(entry_node->name, (const xmlChar *)"DescriptorEntry") == 0) {
            
            SgddEntry* entry = calloc(1, sizeof(SgddEntry));
            if (!entry) continue;
            
            // Parse GroupingCriteria
            xmlNodePtr child = entry_node->children;
            while (child) {
                if (child->type == XML_ELEMENT_NODE) {
                    if (xmlStrcmp(child->name, (const xmlChar *)"GroupingCriteria") == 0) {
                        xmlNodePtr gc_child = child->children;
                        while (gc_child) {
                            if (gc_child->type == XML_ELEMENT_NODE) {
                                if (xmlStrcmp(gc_child->name, (const xmlChar *)"TimeGroupingCriteria") == 0) {
                                    prop = xmlGetProp(gc_child, (const xmlChar *)"startTime");
                                    if (prop) {
                                        strncpy(entry->startTime, (char*)prop, sizeof(entry->startTime)-1);
                                        xmlFree(prop);
                                    }
                                    prop = xmlGetProp(gc_child, (const xmlChar *)"endTime");
                                    if (prop) {
                                        strncpy(entry->endTime, (char*)prop, sizeof(entry->endTime)-1);
                                        xmlFree(prop);
                                    }
                                } else if (xmlStrcmp(gc_child->name, (const xmlChar *)"ServiceCriteria") == 0) {
                                    xmlChar* content = xmlNodeGetContent(gc_child);
                                    if (content) {
                                        strncpy(entry->serviceCriteria, (char*)content, sizeof(entry->serviceCriteria)-1);
                                        xmlFree(content);
                                    }
                                }
                            }
                            gc_child = gc_child->next;
                        }
                    } else if (xmlStrcmp(child->name, (const xmlChar *)"Transport") == 0) {
                        prop = xmlGetProp(child, (const xmlChar *)"ipAddress");
                        if (prop) {
                            strncpy(entry->ipAddress, (char*)prop, sizeof(entry->ipAddress)-1);
                            xmlFree(prop);
                        }
                        prop = xmlGetProp(child, (const xmlChar *)"port");
                        if (prop) {
                            strncpy(entry->port, (char*)prop, sizeof(entry->port)-1);
                            xmlFree(prop);
                        }
                        prop = xmlGetProp(child, (const xmlChar *)"transmissionSessionID");
                        if (prop) {
                            strncpy(entry->transmissionSessionId, (char*)prop, sizeof(entry->transmissionSessionId)-1);
                            xmlFree(prop);
                        }
                        prop = xmlGetProp(child, (const xmlChar *)"hasFDT");
                        if (prop) {
                            strncpy(entry->hasFdt, (char*)prop, sizeof(entry->hasFdt)-1);
                            xmlFree(prop);
                        }
                    } else if (xmlStrcmp(child->name, (const xmlChar *)"ServiceGuideDeliveryUnit") == 0) {
                        SgddDeliveryUnit* unit = calloc(1, sizeof(SgddDeliveryUnit));
                        if (unit) {
                            prop = xmlGetProp(child, (const xmlChar *)"contentLocation");
                            if (prop) {
                                strncpy(unit->contentLocation, (char*)prop, sizeof(unit->contentLocation)-1);
                                xmlFree(prop);
                            }
                            prop = xmlGetProp(child, (const xmlChar *)"transportObjectID");
                            if (prop) {
                                strncpy(unit->transportObjectId, (char*)prop, sizeof(unit->transportObjectId)-1);
                                xmlFree(prop);
                            }
                            
                            // Parse Fragment elements
                            xmlNodePtr frag_node = child->children;
                            SgddFragment* frag_tail = NULL;
                            while (frag_node) {
                                if (frag_node->type == XML_ELEMENT_NODE &&
                                    xmlStrcmp(frag_node->name, (const xmlChar *)"Fragment") == 0) {
                                    
                                    SgddFragment* frag = calloc(1, sizeof(SgddFragment));
                                    if (frag) {
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"transportID");
                                        if (prop) {
                                            strncpy(frag->transportId, (char*)prop, sizeof(frag->transportId)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"id");
                                        if (prop) {
                                            strncpy(frag->fragmentId, (char*)prop, sizeof(frag->fragmentId)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"version");
                                        if (prop) {
                                            strncpy(frag->version, (char*)prop, sizeof(frag->version)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"fragmentEncoding");
                                        if (prop) {
                                            strncpy(frag->fragmentEncoding, (char*)prop, sizeof(frag->fragmentEncoding)-1);
                                            xmlFree(prop);
                                        }
                                        prop = xmlGetProp(frag_node, (const xmlChar *)"fragmentType");
                                        if (prop) {
                                            strncpy(frag->fragmentType, (char*)prop, sizeof(frag->fragmentType)-1);
                                            xmlFree(prop);
                                        }
                                        
                                        // Add to list
                                        if (!unit->fragments) {
                                            unit->fragments = frag;
                                            frag_tail = frag;
                                        } else {
                                            frag_tail->next = frag;
                                            frag_tail = frag;
                                        }
                                    }
                                }
                                frag_node = frag_node->next;
                            }
                            
                            // Add unit to list
                            unit->next = entry->deliveryUnits;
                            entry->deliveryUnits = unit;
                        }
                    }
                }
                child = child->next;
            }
            
            // Add entry to list
            if (!sgdd->entries) {
                sgdd->entries = entry;
                entry_tail = entry;
            } else {
                entry_tail->next = entry;
                entry_tail = entry;
            }
        }
        entry_node = entry_node->next;
    }
    
    return sgdd;
}

/**
 * @brief Correlates ESG fragments by matching service/program IDs
 */
void correlate_esg_fragments(const char* destIp, const char* destPort, 
                             void* lls_tables_ptr, int lls_table_count) {
    
    LlsTable* lls_tables = (LlsTable*)lls_tables_ptr;
    
    // First pass: collect all services and programs
    EsgServiceInfo* all_services = NULL;
    EsgProgramInfo* all_programs = NULL;
    
    for (int i = 0; i < lls_table_count; i++) {
        if (lls_tables[i].type != TABLE_TYPE_ESG_FRAGMENT) continue;
        if (strcmp(lls_tables[i].destinationIp, destIp) != 0) continue;
        if (strcmp(lls_tables[i].destinationPort, destPort) != 0) continue;
        
        EsgFragmentData* frag = (EsgFragmentData*)lls_tables[i].parsed_data;
        if (!frag) continue;
        
        // Merge services
        EsgServiceInfo* svc = frag->services;
        while (svc) {
            // Check if we already have this service ID
            EsgServiceInfo* existing = all_services;
            int found = 0;
            while (existing) {
                if (strcmp(existing->id, svc->id) == 0) {
                    found = 1;
                    // Merge additional data if needed
                    if (strlen(existing->name) == 0 && strlen(svc->name) > 0) {
                        strncpy(existing->name, svc->name, sizeof(existing->name)-1);
                    }
                    if (strlen(existing->description) == 0 && strlen(svc->description) > 0) {
                        strncpy(existing->description, svc->description, sizeof(existing->description)-1);
                    }
                    break;
                }
                existing = existing->next;
            }
            
            if (!found) {
                // Add new service (make a copy)
                EsgServiceInfo* new_svc = calloc(1, sizeof(EsgServiceInfo));
                memcpy(new_svc, svc, sizeof(EsgServiceInfo));
                new_svc->next = all_services;
                all_services = new_svc;
            }
            
            svc = svc->next;
        }
        
        // Merge programs
        EsgProgramInfo* prog = frag->programs;
        while (prog) {
            EsgProgramInfo* existing = all_programs;
            int found = 0;
            while (existing) {
                if (strcmp(existing->id, prog->id) == 0) {
                    found = 1;
                    // Merge data
                    if (strlen(existing->title) == 0 && strlen(prog->title) > 0) {
                        strncpy(existing->title, prog->title, sizeof(existing->title)-1);
                    }
                    if (strlen(existing->description) == 0 && strlen(prog->description) > 0) {
                        strncpy(existing->description, prog->description, sizeof(existing->description)-1);
                    }
                    break;
                }
                existing = existing->next;
            }
            
            if (!found) {
                EsgProgramInfo* new_prog = calloc(1, sizeof(EsgProgramInfo));
                memcpy(new_prog, prog, sizeof(EsgProgramInfo));
                new_prog->next = all_programs;
                all_programs = new_prog;
            }
            
            prog = prog->next;
        }
    }
    
    // Second pass: link schedule events to programs
    for (int i = 0; i < lls_table_count; i++) {
        if (lls_tables[i].type != TABLE_TYPE_ESG_FRAGMENT) continue;
        if (strcmp(lls_tables[i].destinationIp, destIp) != 0) continue;
        if (strcmp(lls_tables[i].destinationPort, destPort) != 0) continue;
        
        EsgFragmentData* frag = (EsgFragmentData*)lls_tables[i].parsed_data;
        if (!frag) continue;
        
        EsgServiceInfo* svc = frag->services;
        while (svc) {
            EsgScheduleEvent* event = svc->schedule;
            while (event) {
                // Find the program this schedule event refers to
                EsgProgramInfo* prog = all_programs;
                while (prog) {
                    if (strcmp(prog->id, event->programId) == 0) {
                        break;
                    }
                    prog = prog->next;
                }
                event = event->next;
            }
            svc = svc->next;
        }
    }
    
}

int count_services(EsgServiceInfo* head) {
    int count = 0;
    while (head) {
        count++;
        head = head->next;
    }
    return count;
}

int count_programs(EsgProgramInfo* head) {
    int count = 0;
    while (head) {
        count++;
        head = head->next;
    }
    return count;
}

void free_esg_data(EsgFragmentData* data) {
    if (!data) return;
    
    // Free services
    EsgServiceInfo* current_service = data->services;
    while (current_service != NULL) {
        EsgServiceInfo* next_service = current_service->next;
        
        // Free service icons
        EsgMediaAsset* current_icon = current_service->icons;
        while(current_icon) {
            EsgMediaAsset* next_icon = current_icon->next;
            free(current_icon);
            current_icon = next_icon;
        }
        
        // Free service schedule
        EsgScheduleEvent* current_event = current_service->schedule;
        while(current_event) {
            EsgScheduleEvent* next_event = current_event->next;
            free(current_event);
            current_event = next_event;
        }
        
        free(current_service);
        current_service = next_service;
    }
    
    // Free programs
    EsgProgramInfo* current_program = data->programs;
    while(current_program != NULL) {
        EsgProgramInfo* next_program = current_program->next;
        
        // Free program icons
        EsgMediaAsset* current_icon = current_program->icons;
        while(current_icon) {
            EsgMediaAsset* next_icon = current_icon->next;
            free(current_icon);
            current_icon = next_icon;
        }
        
        // Free program ratings
        EsgContentRating* current_rating = current_program->ratings;
        while(current_rating) {
            EsgContentRating* next_rating = current_rating->next;
            free(current_rating);
            current_rating = next_rating;
        }
        
        free(current_program);
        current_program = next_program;
    }
    
    free(data);
}
