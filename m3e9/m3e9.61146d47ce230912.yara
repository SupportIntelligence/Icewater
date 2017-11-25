
rule m3e9_61146d47ce230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61146d47ce230912"
     cluster="m3e9.61146d47ce230912"
     cluster_size="292"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['051056e2654704de3736656d40fa3794','077049b8f342a1b3f1540e51db2e1eb6','2ce319adc9257ffdff1cb51154345404']"

   strings:
      $hex_string = { 9bdad9d8dfdedddcd3d2d1d0d7d6d5d4cbcac9c8cfcecdccc3c2c1faf9f8fffefdfcf3f2f1f0f7f6f5f4ebeae9e8efeeedece3e2e1abaaa9a8afaeadaca3a2b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
