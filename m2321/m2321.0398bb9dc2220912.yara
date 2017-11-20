
rule m2321_0398bb9dc2220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0398bb9dc2220912"
     cluster="m2321.0398bb9dc2220912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader axzd"
     md5_hashes="['01d327cad9b210d6d11337c777054154','107fb35a16cc7815afbe8f0fd3e58c5f','fff5929c53553d507bbd1349161c94ca']"

   strings:
      $hex_string = { 8342be164411cbbf8e2f478cb1fa78c8f2bb356e1f393ee677d48f3a23845dfe4668ee120d64dc3785b8c993a90f1d229ca743cdbdcade2af4e3ed1dba98f315 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
