package com.alibou.app.category.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CategoryRequest {

    @NotBlank(message = "VALIDATION.CATEGORY.NAME.NOT_BLANK")
    private String name;
    @NotBlank(message = "VALIDATION.CATEGORY.DESCRIPTION.NOT_BLANK")
    private String description;
}
