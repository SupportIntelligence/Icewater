
rule o3e9_3b1225169da31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.3b1225169da31912"
     cluster="o3e9.3b1225169da31912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mplug multiplug unwanted"
     md5_hashes="['2a333a9f508890fcb5cc61b49b1c4851','904cfc38b509640c238a0f84e3cc3896','fbc6257867eb1db8276480e86db68123']"

   strings:
      $hex_string = { ba4346f6be4742fab24b4efeb64f4ae2aa5356e6ae5752eaa25b64d0986560d49c696cd8906d68dc947174c0887570c48c797cc8cb303781cf343385c3382e9d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
