import "hash"

rule m3e9_5134f7145ee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5134f7145ee31912"
     cluster="m3e9.5134f7145ee31912"
     cluster_size="276 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['80ab890fb9e6c5fc335b06b8ee3b7fb8', 'afae6c69c8452704e0d8ee792a419aca', 'a242872f9450681b274aabc38866bddc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(75776,1536) == "122cbb75d0fd409647be64f54a4238ca"
}

