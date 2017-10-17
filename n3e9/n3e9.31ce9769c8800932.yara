import "hash"

rule n3e9_31ce9769c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ce9769c8800932"
     cluster="n3e9.31ce9769c8800932"
     cluster_size="121 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy orbus malicious"
     md5_hashes="['d28f335be9132116a62557ac20252860', 'bb975636a8d66bf8d07dbaa27ab6832c', 'ab0560a366908ad7d1e741716b5a64b3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1e234acf0ceca011affdfbe810ca8553"
}

