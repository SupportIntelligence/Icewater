
rule n3e9_09119822dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.09119822dabb0932"
     cluster="n3e9.09119822dabb0932"
     cluster_size="33530"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt qmlfrt injector"
     md5_hashes="['0004691e5e826f6f66891252a865a5d1','00077fb22fadf276e274106ab2a952a3','003359e8321b82fc32dda57e28b86887']"

   strings:
      $hex_string = { ce8d356d4a8af496948a066060963f6d0dce9c9a06c92c8d01becffa6337ccf1c898659b7d4d082f6f8447f953ff91aa242cc4cc404aee4dca905b8cfc217db1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
