
rule n2319_6934d51298af4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6934d51298af4912"
     cluster="n2319.6934d51298af4912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['3131a4dccd3ec14a7ef9c1c7dc97c3df957808e9','7efb868df8c178a8170889dc89aa33b25ba70767','618200540c23b381a82c79bd434e97d64f07c7d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6934d51298af4912"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
