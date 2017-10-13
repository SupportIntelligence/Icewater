import "hash"

rule m3ed_531403b999346d16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999346d16"
     cluster="m3ed.531403b999346d16"
     cluster_size="98 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['dc6b4fb4947ed046807be69fb485a3ea', '0e8a91b5d9f5b7ef92d3307e518e895c', 'e0bdd68267acceec89c5b5ecfde2f32c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

