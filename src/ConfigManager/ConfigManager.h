#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H
#include <stdarg.h>

#include "../MySQLConnector/MySQLConnector.h"

typedef struct config_item_t {
    char                  *key;
    char                  *value;
    int                   value_type;
    bool                  clobberable;    // Is this config item overwritable by an automated process?
    struct config_item_t  *next;
} ConfigItem;

typedef struct r_conf_item_t {
    char                  *key;
    struct r_conf_item_t  *next;
} RequiredConfig;


class ConfigManager {
	public:
		ConfigManager(void);
		~ConfigManager(void);
		
		void insertConfigItem(const char *key, const char *val);
		void insertConfigItem(const char *key, const char *val, bool allow_clobber);
		int setExistingConfig(const char *desired_key, const char *value);
		char* getConfigStringByKey(const char *desired_key);
		void freeConfigItemByKey(const char *desired_key);
		int getConfigIpAddress(void);
		int getConfigIntByKey(const char *desired_key);
		int configKeyExists(const char *desired_key);
		void dumpCurrentConfig(void);
		
		void setRequiredConfKeys(int, ...);
		bool isConfKeyRequired(char *);
		bool isConfigComplete(void);

		int loadConfigFromDb(MySQLConnector*);
		
		
	private:
		RequiredConfig *complete_args;
		ConfigItem *current_config;		// The root of the configuration list.

		ConfigItem* newConfigItem(const char *key, const char *val, bool allow_clobber);
		void unloadConfig(void);
};

#endif