
rule k3e9_03aca611d2929932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.03aca611d2929932"
     cluster="k3e9.03aca611d2929932"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart genpack berbew"
     md5_hashes="['c48930c083ecaab8c8ab8aa9353fb0be','d9dd76f5cdab6dbe27e50fcdec798524','ece1fe7ad8b37cce0559c4ab15c6965b']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
