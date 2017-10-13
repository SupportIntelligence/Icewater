import "hash"

rule p3e9_11195ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.11195ec1cc000b12"
     cluster="p3e9.11195ec1cc000b12"
     cluster_size="3514 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['104691c45e9b056894ae725d82b1a3e5', '1e979796c01525d9737f7216fc2067a4', '25ee786987cc7e1f915c3e239b52ce64']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

