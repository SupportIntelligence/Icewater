
rule o3ec_0050ab41d9abd111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ec.0050ab41d9abd111"
     cluster="o3ec.0050ab41d9abd111"
     cluster_size="1035"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob sality"
     md5_hashes="['001c9e94133abfd8fbcc7c28849bf3d6','00506d62100e6aa14bd28bd7c270112f','0594add9f3985c13b5c6bfca0d5672b9']"

   strings:
      $hex_string = { 5e3227330834dd34c135a8368f3776385d39463a253b043ce33cc23da13e803f00602a002c0000005f30413131321833ff33e634cd35b4369b3784386339423a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
