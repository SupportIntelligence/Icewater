
rule m3e9_693f85a499bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85a499bb1912"
     cluster="m3e9.693f85a499bb1912"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['0dbc5c6b531ef415b8a3d66f7639bd0a','1adb19e607d72cf5f34a78ab5914b604','e8138c908aa89a0f3475db92e95f9136']"

   strings:
      $hex_string = { 3ae5fc99055b8a9d6953d1a783d4225f2cbdb9a44d20010fd5a29cbac6aefec4c503c9c3cdd3d0a9e8e9af664f138c967f5c63f6c0d6f0bdf929f4d2e00bf531 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
