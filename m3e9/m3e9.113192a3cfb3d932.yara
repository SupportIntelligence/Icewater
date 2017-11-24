
rule m3e9_113192a3cfb3d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.113192a3cfb3d932"
     cluster="m3e9.113192a3cfb3d932"
     cluster_size="19"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy zbot ngrbot"
     md5_hashes="['05059360b882a48332ceb70826be81a0','05779e5623502b2daf72527d8ef23e46','e70b47c2f65e97b6e64c7227a35a2a11']"

   strings:
      $hex_string = { 9c1d89494b390001ff13416fc2550f1543d81c5eba062aad3c68cbe1a7007f6d7d9054cf99a032617aab3ebdab7a879d7ce8c534036279f6cb85d3985cb9de02 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
