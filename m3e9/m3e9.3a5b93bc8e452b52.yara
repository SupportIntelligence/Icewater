
rule m3e9_3a5b93bc8e452b52
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b93bc8e452b52"
     cluster="m3e9.3a5b93bc8e452b52"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['03f8fc12cde02cc4436c262795c57c2e','4c43ceb01f88a114c22e9083f0d54311','c05e66e795ea6eee6f3abcce8505593d']"

   strings:
      $hex_string = { 3c24f1cb70f6799caa4ae59fe87d1961cc14fad3d636fcd1a7e22311228c5a0449ba9868ce690637419175e94f91bbfe86a83ef808ebc36c3f5f3932a6b7c7ed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
