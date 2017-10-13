import "hash"

rule m3e9_411c96cfc566f312
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c96cfc566f312"
     cluster="m3e9.411c96cfc566f312"
     cluster_size="60 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="allaple madang rahack"
     md5_hashes="['bdddf61a8e8aca981781eaf89175f838', '2f2c78c07db399d5e6541a91a730e750', 'cfbce001964c15a72bb6d27e201522cb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188000,1030) == "b0d7521531466420dcf3da22bbbd2221"
}

