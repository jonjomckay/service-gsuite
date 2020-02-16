package com.jonjomckay.flow.services.gsuite.types;

import com.manywho.sdk.api.ContentType;
import com.manywho.sdk.services.types.Type;

@Type.Element(name = "Domain")
public class Domain implements Type {
    @Type.Property(name = "Domain", contentType = ContentType.String, bound = false)
    private String domain;

    public String getDomain() {
        return domain;
    }
}
