
rule k3ef_319c6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.319c6a49c0000b12"
     cluster="k3ef.319c6a49c0000b12"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious corrupt"
     md5_hashes="['050ae1647e64505378af7bc3f275ebf7','1266dfe3e6be8f1b9e5dceb940321a4b','de0fa74e2e42faaaa566c6ef47387d7d']"

   strings:
      $hex_string = { 5469746c652822446f744e65745a697020534658204172636869766522295d0a00005b617373656d626c793a2053797374656d2e5265666c656374696f6e2e41 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
