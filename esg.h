#ifndef ESG_H
#define ESG_H

#include <libxml/parser.h>
#include <libxml/tree.h>

// ESG data structures
typedef struct EsgMediaAsset {
    char uri[512];
    char contentType[64];
    char usage[32];
    char width[16];
    char height[16];
    struct EsgMediaAsset* next;
} EsgMediaAsset;

typedef struct EsgContentRating {
    char scheme[64];
    char value[128];
    struct EsgContentRating* next;
} EsgContentRating;

typedef struct EsgProgramInfo {
    char id[128];
    char title[256];
    char description[1024];
    char startTime[32];
    char duration[32];
    char genre[128];
    EsgContentRating* ratings;
    EsgMediaAsset* icons;
    struct EsgProgramInfo* next;
} EsgProgramInfo;

typedef struct EsgScheduleEvent {
    char startTime[32];
    char duration[32];
    char programId[128];
    struct EsgScheduleEvent* next;
} EsgScheduleEvent;

typedef struct EsgServiceInfo {
    char id[128];
    char name[256];
    char serviceStatus[16];
    char majorChannel[16];
    char minorChannel[16];
    char genre[128];
    char description[512];
    EsgMediaAsset* icons;
    EsgScheduleEvent* schedule;
    struct EsgServiceInfo* next;
} EsgServiceInfo;

typedef struct {
    EsgServiceInfo* services;
    EsgProgramInfo* programs;
} EsgFragmentData;

// SGDD structures
typedef struct SgddFragment {
    char transportId[32];
    char fragmentId[512];
    char version[32];
    char fragmentEncoding[16];
    char fragmentType[16];
    struct SgddFragment* next;
} SgddFragment;

typedef struct SgddDeliveryUnit {
    char contentLocation[256];
    char transportObjectId[32];
    SgddFragment* fragments;
    struct SgddDeliveryUnit* next;
} SgddDeliveryUnit;

typedef struct SgddEntry {
    char startTime[32];
    char endTime[32];
    char serviceCriteria[512];
    char ipAddress[64];
    char port[16];
    char transmissionSessionId[32];
    char hasFdt[16];
    SgddDeliveryUnit* deliveryUnits;
    struct SgddEntry* next;
} SgddEntry;

typedef struct {
    char id[128];
    char version[32];
    SgddEntry* entries;
} SgddData;

// Function prototypes
EsgFragmentData* parse_esg_service_fragment(xmlDocPtr doc);
SgddData* parse_sgdd(xmlDocPtr doc);
void parse_esg_content(xmlNodePtr content_node, EsgFragmentData* esg_data);
void parse_esg_service(xmlNodePtr service_node, EsgFragmentData* esg_data);
void parse_esg_program(xmlNodePtr program_node, EsgFragmentData* esg_data);
void parse_esg_schedule(xmlNodePtr schedule_node, EsgFragmentData* esg_data);
void parse_esg_service_bundle(xmlNodePtr bundle_node, EsgFragmentData* esg_data);
EsgMediaAsset* parse_esg_media_asset(xmlNodePtr asset_node, const char* usage_type);
EsgContentRating* parse_esg_content_rating(xmlNodePtr rating_node);
void parse_esg_schedule_events(xmlNodePtr schedule_node, EsgScheduleEvent** head, EsgScheduleEvent** tail);
void correlate_esg_fragments(const char* destIp, const char* destPort, 
                             void* lls_tables, int lls_table_count);
int count_services(EsgServiceInfo* head);
int count_programs(EsgProgramInfo* head);
void free_esg_data(EsgFragmentData* data);

#endif // ESG_H
