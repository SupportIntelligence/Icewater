
rule p3e9_499ebb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.499ebb49c8000b12"
     cluster="p3e9.499ebb49c8000b12"
     cluster_size="284"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock yvuuxcfii nabucur"
     md5_hashes="['02c0ed412bc0b68c160e27c73c872a4d','038063f7a22b3065f0e27b8268e7f8b5','28ee3b6e6da2fb3601e3a47d5d775dd9']"

   strings:
      $hex_string = { 0029292903c3c8cc7ba46d58ffc33c04ffc4591effca6426ffd06a25ffd37230ffe29d73fff1c6aeffecdfd6ffc9eef6ff9fe5f5ff5fceeaff39c3e5ff56cde7 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
