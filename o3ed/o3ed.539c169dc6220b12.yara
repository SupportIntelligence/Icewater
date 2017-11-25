
rule o3ed_539c169dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539c169dc6220b12"
     cluster="o3ed.539c169dc6220b12"
     cluster_size="1597"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['00d1a7e544a875f94b99cd8a3e1c3bfe','00d5a965195dda7ba571ca25acc5e0ad','03a12173fce75e1fdcca27620d4d9533']"

   strings:
      $hex_string = { 66833e2e74ba5657ff15f4e314105959b0015eeb0232c08b4dfc5f33cd5be8292a0500c9c20c00558dac2464fcffff81ec1c040000a128c8191033c589859803 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
