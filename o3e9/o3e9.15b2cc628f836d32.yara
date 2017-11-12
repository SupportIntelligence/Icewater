
rule o3e9_15b2cc628f836d32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.15b2cc628f836d32"
     cluster="o3e9.15b2cc628f836d32"
     cluster_size="50"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['01f256a2787121de368670df039f188b','0db4fabc847589a6998e300acf3e49f3','5d144804b137da26d6b2c1620968f4e9']"

   strings:
      $hex_string = { c8c0ce2dd0f7aefcad0835b49def546410f52d27b3a3b0108156404ffed4f35736e257be3feb62e11bd8901b59af9145c536e87bb892106c91502c0bcd1e84ba }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
