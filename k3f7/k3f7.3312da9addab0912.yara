
rule k3f7_3312da9addab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3312da9addab0912"
     cluster="k3f7.3312da9addab0912"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['0fbb1deffc54c1da3226803b597eb0c1','101e0583d4c957f2d2207c02d598f5df','e4f142d73be3e2f07bf0724bf9782780']"

   strings:
      $hex_string = { 322e31272c626c6f673a273239383630343233272c706f73743a2730277d293b0a09766172206c6f61645f636d63203d2066756e6374696f6e28297b6c696e6b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
