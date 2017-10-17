import "hash"

rule n3f4_5246a448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.5246a448c0000b12"
     cluster="n3f4.5246a448c0000b12"
     cluster_size="130 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy genericrxbc selfstarterinternettrojan"
     md5_hashes="['dd1fd2f620b7f80f015cb52c1417754a', '4ea78536a32cb56a88fd9decde7871a5', 'd773833e54f54a5e7b1b6ea614d49f96']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(123904,1280) == "c3df00b6c69147b215b431cae92ce928"
}

