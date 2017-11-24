
rule m2319_3b912aceea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b912aceea210912"
     cluster="m2319.3b912aceea210912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['18a9696c5952aeacc62ff322aa4ac9de','2af095df5a6d31a7645d1ad8b20e0a70','e60924e8be6e1ad7eb94576d3e9646bc']"

   strings:
      $hex_string = { 646f63756d656e742e676574456c656d656e744279496428274e61766261723127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
