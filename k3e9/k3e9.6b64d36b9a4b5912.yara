import "hash"

rule k3e9_6b64d36b9a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9a4b5912"
     cluster="k3e9.6b64d36b9a4b5912"
     cluster_size="132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['e697bfb94566192d135be40e62b81e92', 'c4149afa8a54415f663015b0d0a365f3', '79787172a4fe1f4a4f124ac5f64a347c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23792,1036) == "663025776e46806a4b7c0489da905646"
}

