
rule k3e9_3b9554bcd99bd916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b9554bcd99bd916"
     cluster="k3e9.3b9554bcd99bd916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cossta farfli"
     md5_hashes="['a4f111deb4a806904f44218ce6ea5ef6','b859cdf0e6d96b6c2a6785a1ac454ac3','e95703844693eb17b3b079085f64d5e9']"

   strings:
      $hex_string = { 956ff157388f65ae3dc239b97ce6fc986029b3b54575dc21e799d22c58bf2aa3a314fafd047224701df5645d6ae671e447a941ff4af6cf857e6e7315cea80918 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
