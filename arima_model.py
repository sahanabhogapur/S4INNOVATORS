import pandas as pd
import numpy as np
from statsmodels.tsa.arima.model import ARIMA
from sklearn.metrics import mean_squared_error
import warnings
warnings.filterwarnings('ignore')

class ARIMAModel:
    def __init__(self):
        self.model = None
        self.best_params = None
        
    def find_best_arima_params(self, data):
        p_values = range(0, 3)
        d_values = range(0, 2)
        q_values = range(0, 3)
        
        best_aic = float("inf")
        best_params = None
        
        for p in p_values:
            for d in d_values:
                for q in q_values:
                    try:
                        model = ARIMA(data, order=(p, d, q))
                        model_fit = model.fit()
                        aic = model_fit.aic
                        
                        if aic < best_aic:
                            best_aic = aic
                            best_params = (p, d, q)
                    except:
                        continue
                        
        return best_params
    
    def train(self, data):
        # Find best parameters
        self.best_params = self.find_best_arima_params(data)
        
        # Train the model
        self.model = ARIMA(data, order=self.best_params)
        self.model = self.model.fit()
        
        return self.model
    
    def forecast(self, steps=30):
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
            
        # Generate forecast
        forecast = self.model.forecast(steps=steps)
        
        # Create date range for forecast
        last_date = pd.to_datetime(data.index[-1])
        forecast_dates = pd.date_range(start=last_date + pd.Timedelta(days=1), periods=steps)
        
        # Create forecast DataFrame
        forecast_df = pd.DataFrame({
            'date': forecast_dates,
            'forecast': forecast
        })
        
        return forecast_df
    
    def evaluate(self, data, test_size=0.2):
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
            
        # Split data into train and test
        train_size = int(len(data) * (1 - test_size))
        train, test = data[:train_size], data[train_size:]
        
        # Make predictions
        predictions = []
        for t in range(len(test)):
            model = ARIMA(train, order=self.best_params)
            model_fit = model.fit()
            pred = model_fit.forecast()[0]
            predictions.append(pred)
            train = pd.concat([train, pd.Series([test[t]], index=[test.index[t]])])
        
        # Calculate RMSE
        rmse = np.sqrt(mean_squared_error(test, predictions))
        
        return rmse 