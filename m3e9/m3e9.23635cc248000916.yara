
rule m3e9_23635cc248000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.23635cc248000916"
     cluster="m3e9.23635cc248000916"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted classic"
     md5_hashes="['0cfe3987aec4e9d4a28c27c0062d7de8','1b1f9bff69933aaf24c1e724ee3b093a','ff4e20e4c99eeee472d10ac4638dee05']"

   strings:
      $hex_string = { 98404c0e49834658c7fe45e3577d4ae562535d611d90232eb943007fcde68ad928eb5f5517ba1f6fca9d1bee4f80182008d895b3aac094f232d48ef3d7650bcb }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
