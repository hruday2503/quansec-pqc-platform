#include "ml_kem_plugin.h"
#include "ml_kem_ke.h"

#define ML_KEM_768  1050
#define ML_KEM_1024 1051

typedef struct private_ml_kem_plugin_t private_ml_kem_plugin_t;
struct private_ml_kem_plugin_t {
    plugin_t public;
};

static plugin_feature_t features[] = {
    PLUGIN_REGISTER(KE, ml_kem_ke_create),
        PLUGIN_PROVIDE(KE, ML_KEM_768),
        PLUGIN_PROVIDE(KE, ML_KEM_1024),
};

static int get_features(plugin_t *plugin, plugin_feature_t *f[]) {
    *f = features;
    return countof(features);
}

static char* get_name(plugin_t *this) {
    return "ml-kem";
}

static void destroy_plugin(private_ml_kem_plugin_t *this) {
    free(this);
}

plugin_t *ml_kem_plugin_create() {
    private_ml_kem_plugin_t *this;
    INIT(this,
        .public = {
            .get_name     = get_name,
            .get_features = get_features,
            .destroy      = (void*)destroy_plugin,
        },
    );
    return &this->public;
}
