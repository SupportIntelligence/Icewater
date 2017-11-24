
rule m2319_4930c40addeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4930c40addeb0912"
     cluster="m2319.4930c40addeb0912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker autolike clicker"
     md5_hashes="['024d6e96b298cf0345785d270ed96cfb','7e8a586d7e505b647a4af62d4f4f17e5','f112d9feebbdd5805b89a5a5621c76b6']"

   strings:
      $hex_string = { 49642827466f6c6c6f774279456d61696c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
