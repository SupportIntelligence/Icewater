
rule o3e9_353494f298bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.353494f298bb1912"
     cluster="o3e9.353494f298bb1912"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmu mikey malicious"
     md5_hashes="['041d3783611ed91d9edbed5141365802','0f5f602711edfb38fc6cb39878c14eec','e23a2e9ee194089c76e78a390ea88de5']"

   strings:
      $hex_string = { 0719ae27f384005771e71e6874c83247c48a98859d7da878f83135f74555815c3d96a443cfcad5f5c9bdf9938675efea44e94e5049faa90a0b34051f773687ad }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
