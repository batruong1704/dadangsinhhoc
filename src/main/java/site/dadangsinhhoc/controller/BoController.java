package site.dadangsinhhoc.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import site.dadangsinhhoc.models.BoModel;
import site.dadangsinhhoc.dto.response.ResponseObject;
import site.dadangsinhhoc.services.BoService;

@RestController
public class BoController {
    private final BoService boService;

    @Autowired
    public BoController(BoService boService) {
        this.boService = boService;
    }

    @GetMapping("/getAllBo")
    public ResponseObject getAllBo() {
        return boService.getAllBo();
    }

    @GetMapping("/getBoById/{id}")
    public ResponseObject getBoById(@PathVariable long id) {
        return boService.findById(id);
    }

    @GetMapping("/countAllBo")
    public ResponseObject countAllBo() {
        return boService.countAllBo();
    }

    @PostMapping("/addNewBo")
    public ResponseObject addNewBo(@RequestBody BoModel BoModel) {
        return boService.saveBo(BoModel);
    }

    @PutMapping("/update")
    public ResponseObject updateBo(@RequestBody BoModel boModel) {
        return boService.updateBo(boModel);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseObject deleteBo(@PathVariable Long id) {
        return boService.deleteByIdBo(id);
    }

}
