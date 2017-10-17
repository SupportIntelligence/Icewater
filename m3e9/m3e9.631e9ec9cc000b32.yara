import "hash"

rule m3e9_631e9ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631e9ec9cc000b32"
     cluster="m3e9.631e9ec9cc000b32"
     cluster_size="212 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="brdkgzokiu vbkrypt injector"
     md5_hashes="['b560f624796d45f5eea97d965bd04d0e', 'c1461ccba10ec11be5abcebf1edfa4a6', 'd5049c177c35047e473da2f07704b038']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81408,1024) == "bbba8d45598f83db623d488a1ac2de1e"
}

