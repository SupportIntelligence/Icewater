import "hash"

rule o3e9_10a9a166d9a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.10a9a166d9a30932"
     cluster="o3e9.10a9a166d9a30932"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="linkury webtoolbar bdff"
     md5_hashes="['1b87d103b48924f4c3bdbd4c84d2fa46', 'dc4624f9ae610e179a860ac8505b84d9', '7b5dd0c3e7efaa26b210c0928c3ac250']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2537984,1024) == "98d3e0af75dd11a98fe7745e801752a5"
}

