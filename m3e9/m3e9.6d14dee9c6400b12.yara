import "hash"

rule m3e9_6d14dee9c6400b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d14dee9c6400b12"
     cluster="m3e9.6d14dee9c6400b12"
     cluster_size="1701 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="symmi swisyn abzf"
     md5_hashes="['1af2d46e9508764364de57f9b8ed059f', '1fb7fb03beeb8c53d3e4e17c55deed01', '1681a9e2a46f96dfdb943157f05e8438']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8192,1024) == "9f712feaffef3b90b4425924542b4546"
}

