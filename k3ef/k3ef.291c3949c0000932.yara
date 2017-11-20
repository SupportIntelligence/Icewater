
rule k3ef_291c3949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.291c3949c0000932"
     cluster="k3ef.291c3949c0000932"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious attribute"
     md5_hashes="['011df725fa74ce6fe19110938e4900d5','0571d54872c02bcec977eec98194918e','7ef25b30f95bdf5eefe994823bc0ff10']"

   strings:
      $hex_string = { 3a2053797374656d2e5265666c656374696f6e2e417373656d626c795469746c652822446f744e65745a697020534658204172636869766522295d0a00005b61 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
