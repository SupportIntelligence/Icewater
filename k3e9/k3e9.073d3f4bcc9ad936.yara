import "hash"

rule k3e9_073d3f4bcc9ad936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.073d3f4bcc9ad936"
     cluster="k3e9.073d3f4bcc9ad936"
     cluster_size="25430"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="servstart nitol malicious"
     md5_hashes="['0000658d0d862427ecb27450940c0276','0000945051cbdbde996136ab0b9ba000','00559d4664a16bae7244c301f7d73923']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(16384,16384) == "57873b99ca0b4b65f8cac7c4dc7ac09a"
}

