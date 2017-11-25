
rule m3e9_692f85a48e5b4e5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692f85a48e5b4e5e"
     cluster="m3e9.692f85a48e5b4e5e"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['1fb4ed02cc73abb14efce1cc79f7dbea','514eb01e84f43de97d1af207de7a7713','ffd127f092ce3985ab1de230d4e5629a']"

   strings:
      $hex_string = { f736715bf20ee36b03e1924e9eefee24caabe6174448e4a60926e331209c7ac67f77b61b5fe278f9333240fd7d49a5e742a2281aa8f06fdc9891cb04052d15b8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
