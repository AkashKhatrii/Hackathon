
const start_btn = document.getElementById("start-btn");
const quiz_box = document.querySelector(".quiz_box");
const result_box = document.querySelector(".result_box");
const option_list = document.querySelector(".option_list");
const quizTitle = document.querySelector(".title").innerText
const scoreInput = document.querySelector("#scoreTotal");
const calculateScore_btn = document.querySelector("#calculateScore");
const leaderBoard_btn = document.querySelector("#leaderboard-btn");

start_btn.onclick = ()=>{
    quiz_box.classList.add("activeQuiz");
    showQuetions(0); 
    queCounter(1); 
    console.log("Hiiiiiiiim")
}

calculateScore_btn.onclick = () => {
    scoreInput.value = userScore * 4;
}
let scoreTag = 0;
let que_count = 0;
let que_numb = 1;
let userScore = 0;
let counter;
let counterLine;
let widthValue = 0;
// const quit_quiz = result_box.querySelector(".buttons .quit");

// quit_quiz.onclick = ()=>{
//     window.location.reload(); //reload the current window
// }
const next_btn = document.querySelector("footer .next_btn");
const bottom_ques_counter = document.querySelector("footer .total_que");


next_btn.onclick = ()=>{
    if(que_count < questions[quizTitle].length - 1){ //if question count is less than total question length
        que_count++; //increment the que_count value
        que_numb++; //increment the que_numb value
        console.log("que count, que num", que_count, que_numb);
        showQuetions(que_count); //calling showQestions function
        queCounter(que_numb); //passing que_numb value to queCounter
        clearInterval(counter); //clear counter
        clearInterval(counterLine); //clear counterLine
        next_btn.classList.remove("show"); //hide the next button
    }else{
        clearInterval(counter); //clear counter
        clearInterval(counterLine); //clear counterLine
        showResult(); //calling showResult function
    }
}

function showQuetions(index){
    const que_text = document.querySelector(".que_text");
    //creating a new span and div tag for question and option and passing the value using array index
    
    let que_tag = '<span>'+ questions[quizTitle][index].numb + ". " + questions[quizTitle][index].question +'</span>';
    console.log(que_tag)
    let option_tag = '<div class="option"><span>'+ questions[quizTitle][index].options[0] +'</span></div>'
    + '<div class="option"><span>'+ questions[quizTitle][index].options[1] +'</span></div>'
    + '<div class="option"><span>'+ questions[quizTitle][index].options[2] +'</span></div>'
    + '<div class="option"><span>'+ questions[quizTitle][index].options[3] +'</span></div>';
    que_text.innerHTML = que_tag; //adding new span tag inside que_tag
    option_list.innerHTML = option_tag; //adding new div tag inside option_tag
    
    const option = option_list.querySelectorAll(".option");
    // set onclick attribute to all available options
    for(i=0; i < option.length; i++){
        option[i].setAttribute("onclick", "optionSelected(this)");
    }
}

let tickIconTag = '<div class="icon tick"><i class="fas fa-check"></i></div>';
let crossIconTag = '<div class="icon cross"><i class="fas fa-times"></i></div>';

function optionSelected(answer){
    console.log("selected: ",answer)
    clearInterval(counter); //clear counter
    clearInterval(counterLine); //clear counterLine
    let userAns = answer.textContent; //getting user selected option
    let correcAns = questions[quizTitle][que_count].answer; //getting correct answer from array
    const allOptions = option_list.children.length; //getting all option items
    
    if(userAns == correcAns){ //if user selected option is equal to array's correct answer
        userScore += 1; //upgrading score value with 1
        answer.classList.add("correct"); //adding green color to correct selected option
        answer.insertAdjacentHTML("beforeend", tickIconTag); //adding tick icon to correct selected option
        console.log("Correct Answer");
        console.log("Your correct answers = " + userScore);
    }else{
        answer.classList.add("incorrect"); //adding red color to correct selected option
        answer.insertAdjacentHTML("beforeend", crossIconTag); //adding cross icon to correct selected option
        console.log("Wrong Answer");
        for(i=0; i < allOptions; i++){
            if(option_list.children[i].textContent == correcAns){ //if there is an option which is matched to an array answer 
                option_list.children[i].setAttribute("class", "option correct"); //adding green color to matched option
                option_list.children[i].insertAdjacentHTML("beforeend", tickIconTag); //adding tick icon to matched option
                console.log("Auto selected correct answer.");
            }
        }
    }
    
    for(i=0; i < allOptions; i++){
        option_list.children[i].classList.add("disabled"); //once user select an option then disabled all options
    }
    next_btn.classList.add("show"); //show the next button if user selected any option
}
function showResult(){
    quiz_box.classList.remove("activeQuiz"); //hide quiz box
    result_box.classList.add("activeResult"); //show result box
    const scoreText = result_box.querySelector(".score_text");
        //creating a new span tag and passing the user score number and total question number
    scoreTag = '<span> You got <p>'+ userScore +'</p> out of <p>'+ questions[quizTitle].length +'</p></span>';
    scoreText.innerHTML = scoreTag;  //adding new span tag inside score_Text
}

function queCounter(index){
    //creating a new span tag and passing the question number and total question
    let totalQueCounTag = '<span><p>'+ index +'</p> of <p>'+ questions[quizTitle].length +'</p> Questions</span>';
    bottom_ques_counter.innerHTML = totalQueCounTag;  //adding new span tag inside bottom_ques_counter
}
