
rule m2319_39991ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.39991ec1c8000b12"
     cluster="m2319.39991ec1c8000b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['2ddd304976b5534d5493d476eac15287','4772446ccb12c8002ea387e64a96ad1b','ffdb565f3f659de119aad253366d7640']"

   strings:
      $hex_string = { 3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f526567697374657257696467657428275f42 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
