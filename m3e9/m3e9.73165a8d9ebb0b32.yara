import "hash"

rule m3e9_73165a8d9ebb0b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9ebb0b32"
     cluster="m3e9.73165a8d9ebb0b32"
     cluster_size="403 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="swisyn bner mofksys"
     md5_hashes="['0036ad7f70afa157ec57331cd0685343', '0600c98bba9a6c699fae14e939b393c4', 'c1453561eb69954260bc1426af076974']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

