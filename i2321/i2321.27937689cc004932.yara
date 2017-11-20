
rule i2321_27937689cc004932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.27937689cc004932"
     cluster="i2321.27937689cc004932"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['052a71947e4dca4a30439a90cbad749f','92549c88b148084bb8f2f9a0e63ebc8e','d07784e2893300a0181364f91aaf64f6']"

   strings:
      $hex_string = { d8337176274a17d3c0d1e1e938c1cd1657e28ce358c7172a73a55aba90d8627274646c6b283e726dd9cfe1bef895fee7785bf367df3df19df1f7e268cccdc4c2 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
