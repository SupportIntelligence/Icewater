
rule o3e9_0b9349b65852e392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b9349b65852e392"
     cluster="o3e9.0b9349b65852e392"
     cluster_size="260"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0077e961bef13ea40a037aace303e732','014635b622004a1e8a8467b0031a1af9','0ad6adc172b01eda4816066137eb2a39']"

   strings:
      $hex_string = { edb9a07d6a1cf5f972830a3188efffe7291a3edf8d387a3c691da3e236d164549e06d98ec3e4daa4f69577bfe8c8b1d20813527f302f474f39491e65111921a6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
