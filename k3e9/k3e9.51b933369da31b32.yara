import "hash"

rule k3e9_51b933369da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933369da31b32"
     cluster="k3e9.51b933369da31b32"
     cluster_size="152 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['adada2168813de1e66e8d230f1b62ced', 'f1a059a227d15f1b7397daa130df5949', 'd3764e053aa808e62746022f0be2cbfc']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "b64b84b038538c4ad2cc9e52262cbc46"
}

