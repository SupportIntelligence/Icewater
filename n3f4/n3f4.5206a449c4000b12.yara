import "hash"

rule n3f4_5206a449c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.5206a449c4000b12"
     cluster="n3f4.5206a449c4000b12"
     cluster_size="99 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy genericrxbc selfstarterinternettrojan"
     md5_hashes="['a53faf9373b5b8467427f2403af6d0e3', '3900973a01d1a8f0e271ce83bc647f70', 'a9bee3bd2bd55194b6c576e00d08cf92']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(262144,1024) == "b2a9fda50ea8d3b30cf81bbe5563334f"
}

