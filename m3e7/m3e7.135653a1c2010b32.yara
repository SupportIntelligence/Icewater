
rule m3e7_135653a1c2010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.135653a1c2010b32"
     cluster="m3e7.135653a1c2010b32"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma bruhorn"
     md5_hashes="['8d1e02c3e58d93df0fbbd8ef0f3e5cef','aa282167df2fc4de09d194c439108655','eefb0fc50e46b00e872a1943df7c2369']"

   strings:
      $hex_string = { 8bf08d4dc0f7de1bf646f7dee87faffeff8d4db0e811affeff663bf3750de8b3aefeff83c8ff0145d8eb988d45c4c745a0084000008945a88b45d8480fbfc050 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
