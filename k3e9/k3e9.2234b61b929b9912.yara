
rule k3e9_2234b61b929b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2234b61b929b9912"
     cluster="k3e9.2234b61b929b9912"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor peed qukart"
     md5_hashes="['0c41df5906ed6b1010e1257227cbbcad','a4cb883882016ab3c88ce48ba7d87aab','da8a72fb1a63a209384b8977f132a026']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
