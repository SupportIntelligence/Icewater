
rule m3f7_63981ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63981ec1c8000b12"
     cluster="m3f7.63981ec1c8000b12"
     cluster_size="34"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0e30b33fe794c9215e4ac96bcbf974ce','0fe52d84487d0122524edc105a1df093','b1ef3edc37f6b1f9409ad8e70a9284b9']"

   strings:
      $hex_string = { 6e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
