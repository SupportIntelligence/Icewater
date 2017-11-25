
rule m3f7_0931208bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.0931208bc6220b12"
     cluster="m3f7.0931208bc6220b12"
     cluster_size="75"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker trojanclicker"
     md5_hashes="['084a0ae187c277ef5d1cff1faddfbba5','09adef4538a3c5d0e2943cca43909f15','42caa6a64c8b2a60d6271f662a22b5c2']"

   strings:
      $hex_string = { 4f75543667413568777a7130716c38756e4151594842326530746258394666694d35543466517468614e4f6a574a6d69317061566c6358643339377341615a72 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
