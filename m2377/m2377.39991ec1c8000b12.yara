
rule m2377_39991ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.39991ec1c8000b12"
     cluster="m2377.39991ec1c8000b12"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['018682ee33795e50e78089b460c38e87','080a78f1f56608f96a1eb01c42c3e8f8','7b1691aa43571f9655a0619a66d44f3a']"

   strings:
      $hex_string = { 41417138672f6d42375453696c564c426b2f7337322d632f32303133303432363033313131313133372b2d2b436f70792b2832292e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
