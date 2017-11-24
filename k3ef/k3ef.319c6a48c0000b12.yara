
rule k3ef_319c6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.319c6a48c0000b12"
     cluster="k3ef.319c6a48c0000b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious chgt"
     md5_hashes="['0331358a047cf8d6fa17fa119642a10b','155aa15828898c34ebeb3d3a967e5089','8da33c3148f76b88631fa1af668faa90']"

   strings:
      $hex_string = { 3a2053797374656d2e5265666c656374696f6e2e417373656d626c795469746c652822446f744e65745a697020534658204172636869766522295d0a00005b61 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
