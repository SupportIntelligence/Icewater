
rule k24c1_51b6329d96fb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k24c1.51b6329d96fb1932"
     cluster="k24c1.51b6329d96fb1932"
     cluster_size="11"
     filetype = "Dalvik dex file version 035 (Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend trojansms"
     md5_hashes="['06ba8e2899833e7613d0b2ce87510c08','0b143dc624785baa078d3a03f6420687','d166a6d8857dae0a8358184fb4f3babb']"

   strings:
      $hex_string = { 0b70bc3e9c47941eb46f5331ebadc7bf6133e4b8a1ed2664c0dae3738781b1a4dee6300a168f9e6dab3a7f4df70539b9d04a652db1f785ea9af4f3fbd2cae882 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
